# The Innsegl reference stack

This is the first thing to run after cloning. One block of commands, from
nothing, and you will have watched a real agent identity be issued, a real
commit be signed under it, and that commit be verified by a container with **no
route to our database**.

That last part is the whole point of the project, so it is what the first run
demonstrates rather than what the documentation asserts.

MEASURED on a warm machine: `docker compose -f deploy/compose/innsegl.yml up -d`
takes about 8 seconds once the images exist, the whole boot block about a
minute, and `make smoke` about 55 seconds. A genuinely first run is longer, and
the extra time is a dozen image pulls plus one Go build and one npm build
rather than anything this project does at runtime.

> **This is a contract, not a tutorial.** `VERSIONING.md` puts the compose
> reference stack and `make smoke` inside the compatibility surface: if
> `make smoke`, run the way the *previous minor's* README described, fails on a
> new minor, that is a breaking change misfiled as a minor and the release is
> blocked. The commands below are executed verbatim by `test/smoke`'s OPS-005
> on every CI run, so this file cannot drift from what the smoke actually does.

---

## What you need

| | |
|---|---|
| Docker | a running daemon. The stack is fifteen containers — nine dependencies, six of ours; on Apple Silicon one of them is emulated |
| git | any recent version |
| Go, and `make` | the toolchain `go.mod` names — `make smoke` builds the binary it verifies with |
| `curl` | only for the readiness checks below |

No account, and no Sigstore public-good infrastructure: this stack runs its
**own** Fulcio and its **own** Rekor
([ADR-0010](../../docs/adr/0010-self-hosted-sigstore-is-the-shipped-default.md)).
Nothing here talks to a service anyone else operates.

**The first run does need the network, for two things**, and it is worth
knowing which so that a failure is legible rather than mysterious:

- **About a dozen container images.** Every one is pinned by tag *and* by
  digest, so what you get is byte-for-byte what this was tested against.
- **Go modules** — the project's own dependencies, and `gitsign` at the pinned
  version `v0.17.1`. `gitsign` is deliberately *not* a `go.mod` dependency
  (importing it would drag cosign and sigstore-go into a fourteen-entry module
  for a binary we exec), so `make smoke` fetches and cross-compiles it for the
  container platform on first use. On a warm module cache this is a compile
  rather than a download.

After that first run, nothing leaves your machine.

On Apple Silicon one image, Trillian's database, has no arm64 build and runs
under emulation — it is slow to become healthy the first time, and that is
expected rather than broken.

---

## Boot it

From the repository root:

```sh
export INNSEGL_SPIRE_JWT_ISSUER=http://spire-oidc:8080
docker compose -f deploy/compose/spire.yml up -d
deploy/compose/spire/register.sh
docker compose -f deploy/compose/sigstore.yml up -d
docker compose -f deploy/compose/innsegl.yml build
deploy/compose/spire/register.sh
docker compose -f deploy/compose/innsegl.yml up -d
```

`make innsegl-up` runs exactly that. It is the whole of `docker compose up` for
this project, and every line of it matters:

- **The export comes first.** Three files must name the same issuer — the `iss`
  claim SPIRE stamps, the issuer in the OIDC discovery document, and the
  `oidc-issuers` key Fulcio believes. All three read this variable.
  `spire.yml`'s own default is `https://oidc.innsegl.dev`, an endpoint ADR-0010
  decided is never stood up, and a stack booted on it mints tokens Fulcio
  cannot validate. `sigstore.yml` therefore *requires* the variable rather than
  defaulting it: if you forget the export, compose refuses to start rather than
  starting something subtly wrong.
- **`register.sh` is not optional.** It creates the two bootstrap registration
  entries the stack needs: `spire-oidc`'s own identity, without which the
  discovery provider has no JWKS to publish and Fulcio refuses every token, and
  `innsegl-mcp`'s. It is idempotent, so if it says `no attested agent yet`, the
  agent has not finished attesting: wait a moment and run it again.
- **Order.** `sigstore.yml` attaches to a network `spire.yml` declares and
  owns, and `innsegl.yml` attaches to networks *both* of them own plus the
  SPIRE agent's Workload API socket. Bringing a later stack up first fails
  naming the missing network. That is the correct failure and not a bug.
- **`register.sh` runs twice, and the second run is not a mistake.** Its first
  job is `spire-oidc`'s identity. Its second is `innsegl-mcp`'s — doc 05 §1's
  "only service holding SPIRE admin credential" — and that entry's selectors
  are derived from the `innsegl:local` **image**, which the line above it
  builds. Running it before the build is harmless: it registers `spire-oidc`,
  says the image is not built yet, and exits 0.

  It also writes `deploy/compose/.env`. `innsegl serve` requires the attested
  node's SPIFFE ID, which is not knowable before the stack boots — it is
  `.../spire/agent/x509pop/<sha1 of the agent certificate>`, freshly minted on
  every `up` after a `down -v`. `register.sh` puts it where compose reads it
  for you. The file is gitignored, because it describes one booted stack.
- **`build` before `up`.** Four of the eight services in `innsegl.yml` are the
  same locally-built `innsegl` image and one is the dashboard, so the first
  boot compiles rather than pulls. About a minute, warm.

### Check it came up

```sh
curl -s http://127.0.0.1:8443/keys                  # a JWKS with a key in it
curl -s http://127.0.0.1:5555/api/v1/rootCert       # a PEM CA certificate
curl -s http://127.0.0.1:3000/api/v1/log/publicKey  # a PKIX public key
curl -s http://127.0.0.1:8081/readyz                # the MCP's own readiness
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8082/  # the dashboard
curl -s http://127.0.0.1:8082/api/v1/health         # its backend, and what its
                                                    # credential may do
```

The last line goes through the dashboard's own nginx to `innsegl-api`, so it
answers two questions at once: the proxy is wired, and the query API is up. The
body is the report `api.Open` measured **on the server** — `"role":
"innsegl_reader"`, `"superuser": false`, and eight write probes each refused
with SQLSTATE `42501`. doc 05 §1's "no write credentials mounted" is a fact you
read back rather than a claim in a README; `innsegl api` refuses to start at
all on a credential any of those probes gets past, and there is no flag to turn
that off.

Bytes that parse, not a status code
([ADR-0024](../../docs/adr/0024-readiness-probes-sigstore-by-fetching-its-trust-material.md)):
a TCP dial or an unexamined `200` passes against any listening socket,
including a proxy in front of a dead Fulcio. This is the same question the MCP
server's own `/readyz` asks.

---

## `make smoke` — the first-run contract

```sh
make smoke
```

Takes a few minutes. Exit status is the verdict. It runs **OPS-004** from the
test catalogue, which does four things in order:

1. **Boots this stack from a fresh clone.** It copies the repository's tracked
   and not-ignored files into a temporary directory, takes the two dependency
   compose projects down *with their volumes*, and then runs the **first four
   lines** of the boot block above — through a shell, from that copy. Nothing
   gitignored and no leftover volume can carry the run.

   It does not run `innsegl.yml`. OPS-004 predates those services and stands up
   its own Postgres and its own `innsegl serve` with plain `docker run`; that
   is the gap named under "What the reference stack still does not contain",
   and closing it is a change to a compatibility surface rather than a tidy-up.
2. **Runs the demo agent.** An MCP client, over the real HTTP transport,
   calling the five tools by their published names: `register_agent`,
   `get_credential`, `sign_commit`, `retire_agent`, and a refusal check that
   retirement really is immediate. The commit it produces is signed by the
   Fulcio you just booted and logged in the Rekor you just booted.
3. **Reads the ledger back.** `commit_intent` and `commit_recorded`, in that
   order, linked, with the intent naming no commit — because the intent is
   written *before* the commit exists. That ordering is what lets a reconciler
   later tell a crash from a lie.
4. **Verifies with the ledger detached.** `innsegl verify` runs inside a
   container joined only to the Sigstore stack's published network. Before it
   verifies anything, it proves from that same container that the database is
   unreachable — by address and by name — and it is handed a database
   connection string in its environment anyway. Then all three checks pass:
   certificate chain, transparency-log inclusion, and trailer-to-certificate
   identity.

Step 4 is the reason this exists. Attribution that could only be checked by us,
against our database, would be a claim rather than a proof. Five minutes in,
you have seen a third party's verification succeed with no access to anything
of ours except a git repository and two public endpoints.

> **`make smoke` owns the shipped compose projects for the length of a run.**
> To boot from nothing it removes `innsegl-spire` and `innsegl-sigstore` and
> their volumes, before and after. A stack you brought up by hand will be
> taken down. **Run `make innsegl-down` first** if you have the innsegl stack
> up: it attaches to networks the two dependency projects own, so a `down`
> underneath it leaves those networks alive with an active endpoint and the
> next boot reuses them rather than recreating them. Set `INNSEGL_TEST_KEEP_STACK=1` to leave everything running
> afterwards for inspection; `make smoke-down` then removes it.
>
> For the same reason only one `make smoke` can run on a machine at a time.
> A second one waits on an advisory lock and says so, rather than tearing down
> the first one's stack half way through.

---

## Tear it down

```sh
export INNSEGL_SPIRE_JWT_ISSUER=http://spire-oidc:8080
INNSEGL_SPIRE_PARENT_ID=unset docker compose -f deploy/compose/innsegl.yml \
  --profile demo --profile canary down -v
docker compose -f deploy/compose/sigstore.yml down -v
docker compose -f deploy/compose/spire.yml --profile verify down -v
```

`make innsegl-purge sigstore-down spire-down` runs the same three.

**`make innsegl-down` does not delete the ledger's volume**, and that is
deliberate: the event bodies — `agent_type`, `task_ref`, every `tool_call` —
live in Postgres and nowhere else, and §0 of `runbooks/index-rebuild.md` is
explicit that a sealed segment adjudicates a backup rather than supplying one.
`innsegl-purge` is the one that destroys them, named so that doing it is a
choice. The
`INNSEGL_SPIRE_PARENT_ID=unset` is only there so `down` works after a `down -v`
has already removed the trust material `.env` describes: `innsegl.yml` requires
that variable rather than defaulting it, and a teardown block that cannot tear
down is a worse problem than no teardown block.

`-v` removes the volumes, including the bootstrap PKI. The next boot generates
a fresh trust domain root and a fresh agent identity, so every registration
entry from the old stack is gone with it — which is correct, and is why `down`
*without* `-v` is what you want when you mean to keep a stack across a reboot.

---

## What is in it

[doc 05 §1](../../docs/05-innsegl-deployment-topology.md) names twelve services.
**All twelve ship**, in three compose projects. Each project has its own README,
and the reasoning lives next to the setting it explains rather than in a
summary:

| | |
|---|---|
| [`spire/README.md`](spire/README.md) | `spire-server`, `spire-agent`, `spire-oidc` — the trust domain, workload attestation, and the JWT-SVID → OIDC bridge |
| [`sigstore/README.md`](sigstore/README.md) | `fulcio`, `rekor` and Rekor's backing Trillian log and database — the CA and the transparency log |
| [`innsegl/README.md`](innsegl/README.md) | `postgres`, `minio`, `innsegl-mcp`, `innsegl-reconciler`, `innsegl-sealer`, `innsegl-api`, `innsegl-dashboard`, `demo-agent` — **the components this project is**, and the two database roles they run under: append-only for the writers, read-only for the query API |

The first two are Innsegl's dependencies. The third is Innsegl.

All three stacks are segmented rather than flat: network membership is the
access-control list, and the rule is written at each `networks:` declaration in
the compose files. Fulcio has no route into SPIRE beyond fetching two public
documents; Rekor has no route to Trillian's database; the SPIRE admin API is
reachable from one network with two members, and the second is the MCP it was
declared for. The MCP is on no network with MinIO, and the dashboard is on no
network with the MCP. Neither Postgres nor MinIO publishes a host port, because
a published port is reachable by address from an unrelated bridge network —
measured, and explained in [`innsegl/README.md`](innsegl/README.md). Compose is
where the least-privilege shape is first proven, not first ignored.

MEASURED: thirteen docker networks between the three projects — three for
SPIRE, five more for Sigstore, five more for Innsegl. Docker's default address
pools run out at roughly twenty-nine, and this repository's per-process test
harnesses take up to eight each, so a machine running both may need
`docker network prune` between runs (#100).

---

## See it work

```sh
make innsegl-demo
```

An MCP client — `curl` and a JSON-RPC envelope, sharing nothing with the server
but the protocol — calls the four IP §4 tools by their published names. It
registers an identity, gets a JWT-SVID, stages a commit in the deployment's
workspace, has it signed by the Fulcio you booted and logged in the Rekor you
booted, retires the run, and then proves the retired run cannot spend a
credential. It prints the commit SHA.

Then verify that commit **with no route to the ledger**:

```sh
make innsegl-verify-commit COMMIT=<the sha it printed>
```

That container joins one network — the Sigstore stack's published one — holds a
read-only copy of the working tree and no database credential of any kind, and
is on none of the three ledger networks. All three checks pass: certificate
chain, transparency-log inclusion, and trailer-to-certificate identity.

Two more things worth running once, because both are measurements rather than
claims:

```sh
make innsegl-verify   # ask the server what the MCP's DB credential can do
make innsegl-canary   # SEG-005: prove a sealed segment cannot be deleted
```

---

## The append-only database role

**doc 05 §1 runs the MCP under a database role that can append and cannot
delete.** Until [#109](https://github.com/Raymalian/innsegl/issues/109) nothing
created one, so this stack ran the MCP as the database owner and
`innsegl serve` printed `DATABASE ROLE IS OVER-PRIVILEGED` on an adopter's
first contact with an attestation system.

It does not any more. `innsegl-db-init` creates the role, applies the grants,
and then **connects as the role and asks the server what it can actually do**,
exiting non-zero if the answer is "delete". `innsegl-mcp` gates on its
completion and runs with `-require-append-only-role`, so the server refuses to
start behind anything else. The first line of the MCP's log is now:

```
level=INFO msg="database role is append-only on the chain (doc 05 §1)" role=innsegl_appender granted=[INSERT]
```

The reasoning, the measurement it rests on, and why a check that asked "did the
statement fail?" would pass the database owner are in
[`innsegl/README.md`](innsegl/README.md).

---

## What the reference stack still does not contain

Two things, named here because a first-run experience that quietly omits part
of its topology is worse than one that says so.

**Authentication.** Neither the dashboard nor the query API authenticates
anybody. `innsegl api` authenticates nobody and authorises nothing, and says so
in its own `--help`; doc 05 §3 puts `dashboard.innsegl.dev` behind Cloudflare
Access, and RM-062 (#70) is the issue that does it. Nothing here invents a
scheme in the meantime, and every published port in the stack is bound to
loopback. What *is* enforced is the half that survives a misconfigured proxy:
the credential the query API holds cannot write, whoever reaches it — a
Postgres role the server itself certifies, not the absence of write code.

The dashboard's BFF used to be on this list. It is here now: `innsegl-api`
runs `innsegl api` against `innsegl_reader`, the read-only role
`innsegl-db-init` provisions from `internal/api/readonly.sql`, and
`innsegl-dashboard`'s nginx proxies `/api/v1/` to it. Ask it what its own
credential can do:

```bash
docker compose -f deploy/compose/innsegl.yml exec innsegl-api \
  wget -q -O- http://127.0.0.1:8082/api/v1/health
```

**`make smoke` still prints the over-privileged warning.** OPS-004 does not run
`innsegl.yml`: it starts its own Postgres and its own `innsegl serve` with
plain `docker run`, as the database owner, because it predates these services.
The reference deployment is fixed; the smoke's ad-hoc MCP is not. The fix is
three lines in `test/smoke/smokestack_test.go` — run
`deploy/compose/innsegl/db-init.sh` against the Postgres it already starts,
hand the MCP the `innsegl_appender` DSN, and set
`INNSEGL_REQUIRE_APPEND_ONLY_ROLE` — and it belongs to whoever owns that file,
because `make smoke` is a compatibility surface and changing what it runs is a
release decision.

## Compose defaults versus shipped defaults

doc 05 §1 asked this README to state one asymmetry explicitly — local Fulcio and
Rekor in compose, public Sigstore in the installed product — so that nobody
mistakes a CI convenience for the deployment shape.

**That asymmetry no longer exists.** ADR-0010 measured the question: public-good
Fulcio's allowlist contains no issuer of type `spiffe`, the SPIFFE federation
process was closed `not_planned`, and the machinery that implemented it was
deleted. A project-operated SPIRE trust domain cannot be onboarded there. So
self-hosted Fulcio and Rekor are the shipped default **and** the reference
deployment, in compose and installed alike; public Sigstore is demoted to a
supported configuration, available where a deployment already holds a token
from an issuer on Fulcio's published allowlist.

doc 05 §1's table still describes the old default. That is a spec edit for a
human, not something an implementing agent may make; it is flagged here, in
`sigstore/README.md`, in `spire/README.md` and in ADR-0029.

The consequence to carry away: **whoever deploys Innsegl runs the log that
attests their own agents.** The mechanism is unchanged — a Merkle-backed
append-only log with verifiable inclusion proofs, checkable by anyone holding
the log's public key — but the "even we can't" claim does not survive it.
Every place this project renders non-repudiation must render the log endpoint
in use beside it.

---

## What an agent's identity says about it

The SPIFFE ID grammar is
`spiffe://{trust_domain}/agent/{agent_type}/{task_id}/{run_id}`. That string is
the URI SAN of the Fulcio certificate every commit is signed under, so it is in
the Rekor entry, and it is the `Agent-Identity` trailer, so it is in `git log`.

Filled in literally it reads `spiffe://innsegl.dev/agent/fix-ci/jira-118/run-…`,
and under public Sigstore that ticket number is a permanent public record. So
`innsegl serve` fills those two fields with **keyed pseudonyms** by default
(RM-079):

```
spiffe://innsegl.dev/agent/a7f3c91b/e2d5f004/run-850d52ce…
```

**You do not have to do anything to get this.** `innsegl-identity-init`, a
one-shot with no network at all, mints 32 random bytes into the
`innsegl-identity-secret` volume on the first `up` and leaves them alone on
every `up` after that; `innsegl-mcp` gates on its completion and reads the
file. That is the whole of the setup, and it is a one-shot rather than a value
in `innsegl.yml` for one reason: **a secret shipped in this repository would
give every deployment the same pseudonyms.** `a7f3c91b` would mean one
particular ticket reference in every installation on earth, so resolving one
mapping would resolve it for everybody — worse than not pseudonymising at all,
because it looks private and is not (#124).

Three settings control it:

| Variable | Default | Meaning |
|---|---|---|
| `INNSEGL_IDENTITY_MODE` | `pseudonymous` | `pseudonymous` puts `HMAC-SHA256(secret, "<field>:" ‖ value)`, truncated to 8 hex characters, in `{agent_type}` and `{task_id}`. `literal` puts the caller's own values in. |
| `INNSEGL_IDENTITY_SECRET_FILE` | set by the stack | the file holding the deployment secret. This is what the compose stack uses, because compose can mount a volume and cannot read one into an environment variable — the `INNSEGL_MCP_SVID_FILE` convention. |
| `INNSEGL_IDENTITY_SECRET` | — | the secret as a value, for an invocation that has one to hand. At least 16 bytes. **Setting both this and `INNSEGL_IDENTITY_SECRET_FILE` is refused**, rather than resolved in favour of one: a configuration that quietly picks between two disagreeing sources is how #124 shipped. |

To supply your own instead of the generated one — from a secret store, say:

```sh
export INNSEGL_IDENTITY_SECRET="$(openssl rand -hex 32)"   # then remove
                                                           # INNSEGL_IDENTITY_SECRET_FILE
                                                           # from innsegl-mcp
```

Four things worth knowing before you choose:

- **The server will not start without a secret.** It does not fall back to
  literal values: a configuration that said "private" while every ticket number
  went into Rekor is the failure this default exists to prevent. Choosing
  `literal` is a decision an operator writes down.
- **The real `agent_type` and `task_ref` are still in the ledger**, verbatim, on
  the run's `run_registered` event, beside the pseudonymous `spiffe_id`. That
  row is the whole mapping; there is no second table, and the dashboard resolves
  through it.
- **The secret creates a pseudonym and never resolves one.** Resolution goes
  through that ledger row, so losing or rotating the secret does not orphan
  history and does not strand a running run. Keep the same secret across
  replicas, though: two replicas with different secrets would mint two
  identities for one run.
- **`Agent-Task` carries the pseudonym too**, because it must lowercase to the
  identity's `{task_id}` for the third verification check to settle. The
  attested link from a commit to your tracker therefore lives in the ledger
  rather than in `git log`. Put the ticket in the commit *message* if humans
  need to read it there — that is unattested, and in a public repository it
  leaks, which is why it is a choice rather than a default.

---

## When the first run goes wrong

| Symptom | Cause |
|---|---|
| compose refuses, naming `INNSEGL_SPIRE_JWT_ISSUER` | the export was skipped. This refusal is deliberate; see above |
| `innsegl serve` refuses, naming `-identity-mode / -identity-secret / -identity-secret-file` | the deployment secret is unset, under 16 bytes, or supplied twice. In the shipped stack `innsegl-identity-init` writes it, so check that one-shot's logs first. See "What an agent's identity says about it" |
| `register: FAIL: no attested agent yet` | the SPIRE agent has not finished attesting. Re-run `register.sh`; it is idempotent |
| ports 8443, 5555, 3000, 8080, 8081 or 8082 already bound | the stack publishes those six on loopback. Free them, or override: `INNSEGL_SPIRE_OIDC_PORT`, `INNSEGL_MCP_PORT`, `INNSEGL_MCP_HEALTH_PORT`, `INNSEGL_DASHBOARD_PORT` |
| `all predefined address pools have been fully subnetted` | Docker is out of network address space, at roughly the twenty-ninth network. The three stacks hold twelve between them. `docker network prune` |
| compose refuses, naming `INNSEGL_SPIRE_PARENT_ID` | `register.sh` has not run since this stack booted. It writes `deploy/compose/.env`; re-run it |
| `innsegl-mcp` restarts, logging that the Workload API gave it no SVID | its registration entry is missing or names an older build of `innsegl:local`. Re-run `register.sh` — it detects a stale entry and replaces it |
| `innsegl-db-init` exits non-zero naming a privilege | the ledger's role can do more than append. The message names which privilege; `make innsegl-verify` re-runs the check on its own |
| `innsegl-sealer` restarts | it exits when it cannot reach MinIO or Rekor. `docker compose -f deploy/compose/innsegl.yml logs innsegl-sealer` |
| Fulcio answers `invalid identity token` | the two stacks disagree about the issuer. Bring both down with `-v` and boot again with the export set |
| `trillian-db` never becomes healthy on Apple Silicon | it is emulated; give it longer on the first pull |
| `make smoke` removed a stack you were using | expected — see the note above `make smoke` |
| `make smoke` sits saying it is waiting for a lock | another `make smoke` is running on this machine; there is only one `innsegl-spire` for them to share |
| `go install github.com/sigstore/gitsign` fails | the first `make smoke` needs the network for Go modules; see "What you need" |

Nothing here is published on a routable interface: every port is bound to
`127.0.0.1`. `spire-oidc` in particular serves plain HTTP and says so in two
places in its configuration, because all of `.dev` is HSTS-preloaded and a
production deployment must terminate TLS in front of it.
