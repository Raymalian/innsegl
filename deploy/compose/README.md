# The Innsegl reference stack

This is the first thing to run after cloning. Two commands, from nothing, and
you will have watched a real agent identity be issued, a real commit be signed
under it, and that commit be verified by a container with **no route to our
database**.

That last part is the whole point of the project, so it is what the first run
demonstrates rather than what the documentation asserts.

MEASURED on a warm machine: the boot block below takes about 25 seconds and
`make smoke` about 55 seconds. A genuinely first run is longer, and the extra
time is a dozen image pulls rather than anything this project does.

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
| Docker | a running daemon. The stack is nine containers; on Apple Silicon one of them is emulated |
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
```

That is the whole of `docker compose up` for this project, and every line of it
matters:

- **The export comes first.** Three files must name the same issuer — the `iss`
  claim SPIRE stamps, the issuer in the OIDC discovery document, and the
  `oidc-issuers` key Fulcio believes. All three read this variable.
  `spire.yml`'s own default is `https://oidc.innsegl.dev`, an endpoint ADR-0010
  decided is never stood up, and a stack booted on it mints tokens Fulcio
  cannot validate. `sigstore.yml` therefore *requires* the variable rather than
  defaulting it: if you forget the export, compose refuses to start rather than
  starting something subtly wrong.
- **`register.sh` is not optional.** It creates the one bootstrap registration
  entry the stack needs — `spire-oidc`'s own identity — without which the
  discovery provider has no JWKS to publish and Fulcio refuses every token. It
  is idempotent, so if it says `no attested agent yet`, the agent has not
  finished attesting: wait a moment and run it again.
- **Order.** `sigstore.yml` attaches to a network `spire.yml` declares and
  owns, so bringing Sigstore up first fails naming the missing network. That is
  the correct failure and not a bug.

### Check it came up

```sh
curl -s http://127.0.0.1:8443/keys                  # a JWKS with a key in it
curl -s http://127.0.0.1:5555/api/v1/rootCert       # a PEM CA certificate
curl -s http://127.0.0.1:3000/api/v1/log/publicKey  # a PKIX public key
```

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
   and not-ignored files into a temporary directory, takes both shipped compose
   projects down *with their volumes*, and then runs the boot block above —
   through a shell, from that copy. Nothing gitignored and no leftover volume
   can carry the run.
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
> taken down. Set `INNSEGL_TEST_KEEP_STACK=1` to leave everything running
> afterwards for inspection; `make smoke-down` then removes it.
>
> For the same reason only one `make smoke` can run on a machine at a time.
> A second one waits on an advisory lock and says so, rather than tearing down
> the first one's stack half way through.

---

## Tear it down

```sh
export INNSEGL_SPIRE_JWT_ISSUER=http://spire-oidc:8080
docker compose -f deploy/compose/sigstore.yml down -v
docker compose -f deploy/compose/spire.yml --profile verify down -v
```

`-v` removes the volumes, including the bootstrap PKI. The next boot generates
a fresh trust domain root and a fresh agent identity, so every registration
entry from the old stack is gone with it — which is correct, and is why `down`
*without* `-v` is what you want when you mean to keep a stack across a reboot.

---

## What is in it

Nine containers in two compose projects, both of them
[doc 05 §1](../../docs/05-innsegl-deployment-topology.md)'s reference topology.
Each has its own README, and the reasoning lives next to the setting it
explains rather than in a summary:

| | |
|---|---|
| [`spire/README.md`](spire/README.md) | `spire-server`, `spire-agent`, `spire-oidc` — the trust domain, workload attestation, and the JWT-SVID → OIDC bridge |
| [`sigstore/README.md`](sigstore/README.md) | `fulcio`, `rekor` and Rekor's backing Trillian log and database — the CA and the transparency log |

Both stacks are segmented rather than flat: network membership is the
access-control list, and the rule is written at each `networks:` declaration in
the compose files. Fulcio has no route into SPIRE beyond fetching two public
documents; Rekor has no route to Trillian's database; the SPIRE admin API is
reachable from one network with one intended member. Compose is where the
least-privilege shape is first proven, not first ignored.

---

## What the reference stack does not contain yet

doc 05 §1 lists twelve services. The two compose files here ship five of those
rows — nine running containers, because Rekor's row carries its own log and
database sidecars. The **seven** rows that are not compose services at all are
named here, because a first-run experience that quietly omits half its topology
is worse than one that says so:

| Missing | Consequence for a first run |
|---|---|
| `postgres` (the ledger's hot tier) | `make smoke` starts one itself, on a network of its own, publishing no host port; the MCP applies the shipped migrations to it with its own `-migrate` |
| `innsegl-mcp` | `make smoke` runs `innsegl serve` in a container joined to the three networks doc 05 §1 puts it on, with the shipped binary bind-mounted. There is no Dockerfile and no compose service |
| `innsegl-reconciler`, `innsegl-sealer` | not exercised by the smoke at all; both are the same `innsegl` binary under another subcommand |
| `innsegl-dashboard` | not exercised by the smoke at all; it is the separate TypeScript application under `web/` |
| `minio` (object storage, object lock on) | segment sealing and the SEG-005 deletion canary are not part of the first run |
| `demo-agent` | is the smoke test body itself rather than a container |

Two related consequences you will see with your own eyes on a first run:

- **`innsegl serve` prints `DATABASE ROLE IS OVER-PRIVILEGED` at start-up.**
  doc 05 §1 runs the MCP under a database role that can append and cannot
  delete. Nothing here creates that role, so the smoke's MCP connects as the
  database owner and the server says so, loudly, rather than letting the
  topology's claim go unmeasured. The append-only trigger in
  `migrations/0001_ledger.sql` still refuses `UPDATE`, `DELETE` and `TRUNCATE`
  on the chain — but a trigger is disableable by a superuser and a revoke does
  not bind the table owner, so the deployment really is one `psql` prompt
  weaker than the topology says. Warned, not hidden.
- **The MCP's admin credential is three PEM files, not an attested SVID.** A
  deployment attests the MCP through the Workload API and gets rotation with
  it. That needs a registration entry carrying the MCP container's own
  selectors, which needs the container to exist first — the same circularity
  `register.sh` already solves for `spire-oidc`, and it would have to grow a
  second case. Until it does, the smoke mints the credential over the server's
  local admin socket, as an operator action.

---

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

## When the first run goes wrong

| Symptom | Cause |
|---|---|
| compose refuses, naming `INNSEGL_SPIRE_JWT_ISSUER` | the export was skipped. This refusal is deliberate; see above |
| `register: FAIL: no attested agent yet` | the SPIRE agent has not finished attesting. Re-run `register.sh`; it is idempotent |
| ports 8443, 5555 or 3000 already bound | the stack publishes those three on loopback. Free them, or bring your own stack down first |
| `all predefined address pools have been fully subnetted` | Docker is out of network address space, at roughly the twenty-ninth network. `docker network prune` |
| Fulcio answers `invalid identity token` | the two stacks disagree about the issuer. Bring both down with `-v` and boot again with the export set |
| `trillian-db` never becomes healthy on Apple Silicon | it is emulated; give it longer on the first pull |
| `make smoke` removed a stack you were using | expected — see the note above `make smoke` |
| `make smoke` sits saying it is waiting for a lock | another `make smoke` is running on this machine; there is only one `innsegl-spire` for them to share |
| `go install github.com/sigstore/gitsign` fails | the first `make smoke` needs the network for Go modules; see "What you need" |

Nothing here is published on a routable interface: every port is bound to
`127.0.0.1`. `spire-oidc` in particular serves plain HTTP and says so in two
places in its configuration, because all of `.dev` is HSTS-preloaded and a
production deployment must terminate TLS in front of it.
