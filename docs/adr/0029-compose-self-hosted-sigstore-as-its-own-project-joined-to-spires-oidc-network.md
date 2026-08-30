# ADR-0029: Compose self-hosted Sigstore as its own project joined to SPIRE's OIDC network, give the log a key that survives a restart, and issue no SCT

- Status: accepted
- Date: 2026-08-30
- Deciders: Mike
- Implements: doc 05 §1 (the `fulcio` and `rekor` rows), RM-030 (#38)
- Builds on: [ADR-0010](0010-self-hosted-sigstore-is-the-shipped-default.md),
  [ADR-0009](0009-anchor-a-segment-as-a-signed-hashedrekord-entry.md),
  [ADR-0011](0011-compose-spire-admin-api-segmentation.md),
  [ADR-0022](0022-a-compose-project-per-test-process-for-the-shipped-spire-stack.md),
  [ADR-0024](0024-readiness-probes-sigstore-by-fetching-its-trust-material.md)

## Context

Doc 05 §1 lists `fulcio` and `rekor + its backing log/database services` in the
reference compose stack, with one instruction about the second — "Rekor's
storage dependencies run as sidecars per upstream's own compose reference; pin
versions" — and one about all of it: "Network segmentation even in compose
[...] Compose is where the least-privilege shape is first proven, not first
ignored."

Four things constrain how that can be built, and none of them is about YAML.

**ADR-0010 changed what this file is.** It is no longer the CI convenience doc
05 §1 describes. Public-good Fulcio accepts no issuer of type `spiffe`, the
SPIFFE federation process was closed `not_planned` and its implementation
deleted, so self-hosted Fulcio and Rekor became the *shipped default and the
reference deployment*. Everything below is therefore a decision about a
production artifact, not about a test fixture.

**Most of this already existed and had already been measured.** RM-012 (#20)
stood up the five-container Rekor stack in
`internal/segment/rekorharness_test.go` to prove SEG-003 against a real
transparency log, and recorded two findings that cost real time to find: the
Trillian **log signer** is not optional (without it leaves queue forever, no
inclusion proof ever exists, and the failure presents as a hang rather than an
error), and upstream's Trillian images are amd64-only so the Sigstore
*scaffolding* images have to be used instead. Its report asked for the harness
to be lifted into `deploy/compose/`. A second stack written independently from
upstream's compose would be a second thing to keep true.

**Fulcio needs an issuer it can fetch, and `oidc.innsegl.dev` is not it.**
ADR-0010's decision says in terms: "`oidc.innsegl.dev` is not stood up [...]
The SPIRE OIDC discovery provider stays internal to the deployment, reachable
by the self-hosted Fulcio only." But `deploy/compose/spire.yml` defaults
`INNSEGL_SPIRE_JWT_ISSUER` to `https://oidc.innsegl.dev`, because it was
written before that decision. A stack brought up on those defaults produces
JWT-SVIDs whose `iss` claim names an endpoint that does not exist, and Fulcio
refuses every one of them with `invalid identity token`.

**`spire.yml` is another issue's file and is already load-bearing.** It pins
`name: innsegl-spire`, a fixed `container_name:` per service, and the
ADR-0011 network segmentation; `make spire-up` / `spire-down` and
`spire/register.sh` all address it as `-f deploy/compose/spire.yml` alone; and
`spire-testscope.yml` (ADR-0022) overlays it for per-process test isolation.
Whatever Sigstore does must not disturb any of that.

## Decision

**Six decisions, taken together, all in `deploy/compose/sigstore.yml` and
`deploy/compose/sigstore/`.**

### 1. RM-012's stack is lifted, not rewritten

The service list, the image tags, the flags, the ordering hazards and the
MySQL readiness question are RM-012's, carried over verbatim and marked
`RM-012 FINDING` at the settings that encode them. Two of those marks are the
whole reason this ADR insists on the lift:

- `trillian-log-signer` is a service with a comment saying it must never be
  deleted, and `sigstore/verify.sh` **polls for an inclusion proof with a
  deadline** so that its absence fails with a sentence naming it instead of
  looking like slowness.
- `trillian-db`'s healthcheck is `SELECT 1 FROM test.Trees` over TCP, not
  upstream's `mysqladmin ping`. RM-012 measured that the image boots twice —
  a temporary server with networking disabled, against which the schema is
  applied, then the real one — so a socket probe answers "ready" at a moment
  when nothing on the network can connect and the Trillian pair gets started
  into the gap.

The four Rekor-side image versions are RM-012's exactly. When one moves, both
move, in one change.

**What is added on top is pinning by digest as well as tag**, following
`spire.yml`'s discipline rather than RM-012's (a harness that pulls a tag is
fine; a shipped deployment that does is not).

### 2. Sigstore is its own compose project, joined to SPIRE's OIDC frontend as an external network

`sigstore.yml` declares `name: innsegl-sigstore` and attaches `fulcio` to
`innsegl-oidc-frontend` — the network `spire.yml` already declares for exactly
this purpose ("the one thing outside the deployment has to reach (Fulcio
fetches the discovery document)") — with `external: true`. That is the entirety
of the wiring between the two stacks: Fulcio reads two public documents, the
discovery document and the JWKS, over one network. It is on no network with
`spire-server` and cannot open a socket to the Agent API or the admin API.

The network's name is `${INNSEGL_SIGSTORE_OIDC_NETWORK:-innsegl-oidc-frontend}`
so that an ADR-0022 test overlay can point it at a per-process SPIRE stack's
frontend network without editing this file.

### 3. One variable names the issuer, and it is required rather than defaulted

`INNSEGL_SPIRE_JWT_ISSUER` is read by `spire/server.conf` (the `iss` claim),
`spire/oidc-discovery-provider.conf` (the discovery document) and — newly —
`sigstore/fulcio-config.yaml` (the issuer Fulcio believes). The compose value
is `http://spire-oidc:8080`: the service name on the shared network, which is
already on the discovery provider's `domains` allowlist.

Fulcio has no environment expansion, so `sigstore/bootstrap.sh` renders the
config from the template with that variable substituted, on every run. The
variable is spelled `${INNSEGL_SPIRE_JWT_ISSUER:?...}` in `sigstore.yml` —
required, not defaulted, adopting `spire-testscope.yml`'s reasoning verbatim —
and `make sigstore-up` sets it for **both** compose files in one place.
`sigstore/verify.sh` additionally asserts that the `iss` claim on the minted
JWT-SVID equals the issuer Fulcio was configured for, because that mismatch is
the single most likely misconfiguration in the stack and Fulcio's own error
message does not name it.

### 4. The transparency log's key lives on disk, not in memory

RM-012's harness uses `--rekor_server.signer=memory`; this file uses a P-256
key generated once by the bootstrapper and mounted read-only. **This is the one
deliberate divergence from the lift**, and ADR-0009 is the reason. Its decision
2 verifies an anchor from first principles and ends: "the checkpoint's
signature must verify under the log's key. Only the last step trusts anything,
and what it trusts is a key." A memory signer mints a new key on every restart,
so every segment anchored before a `docker compose restart rekor` becomes
unverifiable — silently, because the entry is still in the log and only the
signature check fails. For a test harness memory is correct; for the shipped
default it is a correctness bug. The bootstrapper never regenerates the key
once it exists, and says so where it would.

### 5. There is no CT log, and no SCT is issued

Doc 05 §1's table has no row for a Certificate Transparency log, so none is
added; `--ct-log-url=` (empty) turns Fulcio's submission off and it logs
"Skipping CT log upload", returning the certificate with an empty detached SCT.
This is recorded as a decision rather than left as an omission because it has a
consequence two issues downstream: **a verifier configured to require an SCT
will refuse these certificates.** RM-032 (gitsign wrapper) and RM-037 (`innsegl
verify`) must be built against a trust root that lists no CT log.

### 6. Least privilege is six networks, and one of them exists for a mechanical reason

- `innsegl-oidc-frontend` (external) — `spire-oidc`, `fulcio`.
- `innsegl-sigstore` (internal) — `fulcio`, `rekor`, and the `innsegl-*`
  services when they land.
- `innsegl-sigstore-rekor-log` (internal) — `rekor`, `trillian-log-server`.
- `innsegl-sigstore-rekor-index` (internal) — `rekor`, `rekor-redis`. A
  two-member network in place of upstream's `--requirepass test`: nothing else
  can open a socket to Redis at all, which a shared password on a shared
  network does not achieve.
- `innsegl-sigstore-trillian-db` (internal) — the Trillian pair and MySQL.
  **Rekor is deliberately not a member**: the front end, the one component a
  verifier talks to, has no route to the database its proofs are built from.
- `innsegl-sigstore-published` (**not** internal) — `fulcio`, `rekor`.

That last network is not decoration and must not be tidied away. MEASURED: a
container attached only to `internal` networks cannot have a port published.
With `rekor` on the three internal networks and nothing else, `docker port
innsegl-sigstore-rekor` printed `3000/tcp` with no host binding,
`.NetworkSettings.Ports` was `{"3000/tcp":[]}`, and the host could not connect
— while `fulcio`, which happened also to be on the non-internal OIDC frontend,
published fine. An internal network has no gateway, so there is nothing to NAT
through. Rather than un-internalling `innsegl-sigstore` and handing egress to
every `innsegl-*` service that later joins it, the two services that must be
reachable from outside get one narrow network of their own.

## Alternatives considered

**`docker compose -f spire.yml -f sigstore.yml` as a merged project.** The
obvious reading of "one compose stack", and it loses on three concrete points.
`spire.yml` pins `name: innsegl-spire`, so the merged project is named after
half of itself or the merge has to override the name — and then `make
spire-up`, `make spire-down` and `spire/register.sh`, which all address
`-f spire.yml` alone, build and tear down a *different* project than the merged
one, so a developer who runs both ends up with two SPIRE stacks. Merge order
would also become load-bearing for every key the two files share, which is the
kind of coupling that is invisible until it breaks. And `docker compose -f
deploy/compose/sigstore.yml config` — the first thing a reviewer runs — would
stop working on its own. The external-network form gives the same single
runtime topology with none of that; the price is that `up` requires the SPIRE
stack to exist first, which fails with a message naming the missing network.

**An overlay file, in the shape of `spire-testscope.yml`.** That pattern exists
to rename an *existing* stack's parts, not to add services with their own
lifecycle. Rekor in particular is useful without SPIRE at all — SEG-003
anchors against it with no identity involved — and an overlay would tie the log
to a stack it does not need.

**Un-internalling `innsegl-sigstore` to get published ports.** One line
shorter, and it hands off-host routing to every service that later joins the
network the MCP and the sealer will sit on. Rejected for the narrow
`innsegl-sigstore-published` network instead.

**Keeping `--rekor_server.signer=memory` for fidelity with RM-012.** The lift
is a means, not the goal. Shipping a log that forgets its identity on restart
would make ADR-0009's verification chain terminate on a key that no longer
exists.

**Adding a CT log (upstream's compose now runs `tesseract`).** Two more
containers and a second log to operate, for a property doc 05 §1 does not ask
for and no v0.1 verifier consumes. Recorded above as a decision with a named
consequence, so it can be revisited by RM-032 on evidence rather than
rediscovered.

**Standing up `oidc.innsegl.dev` so Fulcio fetches a real public issuer.**
Forbidden by ADR-0010 decision 1 and by doc 05 §3's condition, which is not
met by any Fulcio we can reach.

## Consequences

**The compose stack now has a second required bring-up step, and `make
sigstore-up` is it.** Bringing up `spire.yml` on its defaults produces
JWT-SVIDs Fulcio will refuse. The Makefile target sets the issuer for both
files; the README says why; and `verify.sh` fails with a sentence naming the
mismatch if somebody does it by hand and gets it wrong.

**`deploy/compose/spire.yml`'s default issuer is now wrong for every path the
project actually uses.** It defaults to `https://oidc.innsegl.dev`, which
ADR-0010 decided is never built. Changing it is RM-014's file, not this
issue's; it is flagged here and in `sigstore/README.md` rather than edited.

**Nothing in this stack has an in-container healthcheck except MySQL and
Redis.** Fulcio, Rekor and both Trillian services are distroless — no shell,
no curl, nothing to probe with. This is `spire-oidc`'s situation and takes
`spire-oidc`'s answer: readiness is probed from outside over HTTP, and
ADR-0024 already fixes *what* to probe (Fulcio's `/api/v1/rootCert` must decode
as a PEM CA certificate, Rekor's `/api/v1/log/publicKey` as a PKIX public key).
Ordering is handled the way RM-012 handled it, with `restart: on-failure`.

**The log-operator concentration ADR-0010 named is now concrete.** This
deployment runs the CA that attests its own agents and the log that records
them. The mechanism still works — a Merkle-backed append-only log with
verifiable inclusion proofs — and `verify.sh` demonstrates one end to end. The
"even we can't" claim does not, and every place the project renders a
non-repudiation claim must say which log it means.

**The Fulcio CA key password is not a secret boundary and the file says so.**
It sits on Fulcio's command line where `docker inspect` shows it, next to the
key it protects. What protects the key is the mount table — one writer, one
reader, read-only, mode 0400. The password exists because `fileca` requires an
encrypted PKCS#8 key.

**No new production code, so no new test-catalog IDs.** RM-030 produces
configuration and infrastructure; per its own acceptance criteria the
verification is the criteria themselves. `sigstore/verify.sh` is the
executable form of that and is not TC-SIG: SIG-001 is a signed *commit*
verified through the shipped tooling, and belongs to E5's Go tests against this
stack. Nothing under `internal/` changed.

## What the project should do next

1. **RM-032 and RM-037 must configure their verifiers for a trust root with no
   CT log**, per decision 5. If that turns out to be expensive, adding a CT log
   here is a bounded change and this ADR is the place to revisit it.
2. **When a Go harness starts driving this stack, give it an ADR-0022 overlay.**
   Today it is brought up by hand or by `make`; nothing under `internal/` or
   `test/` touches it. The external network name is already parameterised so
   that overlay is a rename, not a rework.
3. **Re-pin on a schedule.** Six digests are frozen in `sigstore.yml`. Moving
   Rekor means moving `internal/segment/rekorharness_test.go` in the same
   change, or the stack and the test that proved it stop describing the same
   log.

## For the human — a spec edit this ADR does not make

**Doc 05 §1's `fulcio` row is now factually wrong.** It reads: "Compose default
is the **local** stack so CI needs no network; the *installed product* default
is public Sigstore per ADR-0002 — the compose README states this asymmetry
explicitly." ADR-0010 removed that asymmetry: self-hosted is the default in
both, and public Sigstore is the configured-in option "where an accepted issuer
already exists". The instruction to the compose README therefore asks it to
state something untrue.

The compose README states the *current* position instead, and names the row as
stale. Doc 05 is a spec document and an implementing agent may not edit it.
ADR-0010's own Consequences already anticipated this — "Doc 05 loses the
`oidc.innsegl.dev` row's urgency and gains a self-hosted-Sigstore topology it
must describe; that is an edit for the human, not for an implementing agent" —
and this is the second, narrower half of that same edit: the `fulcio` row's
Notes column, and doc 05 §3's `oidc.innsegl.dev` row, which decision 1 of
ADR-0010 has already decided is not built.
