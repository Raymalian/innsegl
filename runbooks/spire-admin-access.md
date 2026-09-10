# Runbook — reaching the SPIRE admin API for `innsegl init`

**RM-097 deliverable (#156).** `spire.yml` publishes no port for `spire-server`
and puts it on an `internal: true` network, on purpose — ADR-0011 and the
service's own comment: "an unauthenticated admin listener on a developer's
machine is worse than the inconvenience it removes." `innsegl init
-trust-root self-hosted` needs that API to mint the test signature that makes
setup provable (#117 point 4). This runbook is the three ways to bridge that
gap, each tried against a real stack, with the measured cost of each — and a
recommendation.

All three were run against a stack booted with:

```sh
export INNSEGL_SPIRE_JWT_ISSUER=http://spire-oidc:8080
export INNSEGL_REKOR_PORT=3010   # only if 23000 is already taken
make innsegl-up
```

---

## Option 2 — run `innsegl init` inside the deployment (recommended)

Nothing is published, ever. `innsegl-init` (`deploy/compose/innsegl.yml`) is a
one-shot job — the same shape as `demo-agent` and `innsegl-canary` — that
reuses `innsegl-mcp`'s image, uid and `dev.innsegl.component` label. Those are
exactly the five selectors `register.sh` already matched to
`spiffe://innsegl.dev/innsegl/mcp`, so this container is attested with the
*same* admin identity the running MCP holds, over the Workload API socket, on
`innsegl-spire-admin`. No second admin identity is registered; `server.conf`'s
`admin_ids` and `authz-policy.rego` are unchanged.
`cmd/innsegl/initsignharness_test.go` already calls exactly this
impersonation "the right impersonation, not a shortcut" for its own test
credential — this is that same resolution, run inside the deployment instead
of minted by hand for a test.

### What an operator types

```sh
make innsegl-init REPO=/path/to/your/repo ARGS='-trust-root self-hosted \
  -gitsign-path /usr/local/bin/gitsign -non-interactive -identity-mode pseudonymous'
```

or, without `make`:

```sh
docker compose -f deploy/compose/innsegl.yml --profile init run --rm \
  --volume "$(pwd)":/target innsegl-init \
  init -repo /target -trust-root self-hosted -gitsign-path /usr/local/bin/gitsign \
  -non-interactive -identity-mode pseudonymous
```

**Measured**, against a throwaway repository, on this stack:

```
git config --local: gpg.format=x509, gpg.x509.program=/usr/local/bin/gitsign (recorded, not activated — commit.gpgsign is not set, and this command does not set it)
deployment config written: .innsegl/deploy.env, .git/innsegl/identity-secret
VERIFIED: this deployment can sign. refs/innsegl/init-verify signed a real commit (0fcfe397f9c8df57569eb3f97686ce4a9cdba06e) as an orchestrated identity, and `innsegl verify` accepted it. [...]
```

### What is exposed, and for how long

**Nothing published, ever.** This is `docker compose run --rm`: the container
exists for the length of one `init` invocation and is removed automatically
when it exits — confirmed (`docker ps -a` shows nothing left behind
immediately after the run above). What the container holds *while it runs* is
the same admin reach `innsegl-mcp` already holds continuously; nothing new is
granted, and there is nothing new to revoke afterwards.

### Failure mode if the operator forgets to undo it

There is nothing to forget. A `run --rm` job that hangs still cannot be
reached from outside the deployment — it published no port — and it holds no
more privilege than the MCP already holds for as long as the stack is up.
This is the property the other two options do not have.

### The real costs, measured

- **`-gitsign-path` is not optional here.** The image already carries a
  pinned, verified `gitsign` at `/usr/local/bin/gitsign` (see `Dockerfile`),
  but `innsegl-spire-admin` and `innsegl-sigstore` are both `internal: true`
  — there is no route out to GitHub for `init`'s own download-and-verify
  fallback. Omitting the flag fails cleanly (a download error), it does not
  silently proceed unsigned.
- **The target repository is a host bind mount** (`--volume host:/target`),
  which is new to this compose stack — everywhere else uses named volumes.
  MEASURED on this machine (macOS, Docker Desktop): files `init` wrote showed
  up on the host owned by the invoking user with no `chown` or
  `safe.directory` needed, because Docker Desktop's file-sharing layer
  reconciles container and host ownership transparently. **Not measured**:
  behaviour on native Linux, where a bind mount preserves the writing
  container's real uid (1000) verbatim. An operator hitting "detected
  dubious ownership" there needs `git config --global --add safe.directory
  <repo>` on the host, or files owned by a uid the container cannot write to
  needs a `chown`. Flagged as an assumption, not measured here.
- **`-oidc-issuer`'s flag has a surprising env fallback**: `cmd/innsegl/serve.go`
  names it `INNSEGL_SPIRE_JWT_ISSUER`, not `INNSEGL_OIDC_ISSUER` — the
  compose service sets that exact variable so the operator does not have to
  know this, but it is worth stating since it looks like the wrong name at
  first read.

---

## Option 1 — the socat admin relay, as a compose profile

`spire-admin-relay` (`deploy/compose/spire.yml`), profile `adminrelay`, **off
by default**. It is the shape every test harness in this repository already
builds for itself (`alpine/socat:1.8.0.3`, pinned by digest): a container on
`innsegl-spire-admin` that also joins one new, narrow, non-internal network
(`innsegl-spire-admin-relay`) purely so its port can be published — MEASURED
(see `sigstore.yml`'s own note): a container on `internal: true` networks
only cannot have a port published at all; there is no gateway for Docker to
NAT through. It changes nothing about `spire-server`'s own authorization —
`admin_ids` and the OPA policy are exactly as before. A caller still needs a
real admin credential; the relay only carries bytes.

### What an operator types

```sh
make spire-admin-relay-up

# mint a bootstrapping admin credential the way register.sh's own helper does
docker compose -f deploy/compose/spire.yml exec -T spire-server \
  /opt/spire/bin/spire-server x509 mint -spiffeID spiffe://innsegl.dev/innsegl/mcp -ttl 1h \
  -socketPath /run/spire/admin/api.sock > mint.out
# split mint.out into svid.pem / key.pem / bundle.pem at the "X509-SVID:",
# "Private key:" and "Root CAs:" headings (see initsignharness_test.go's
# signE2ESection for the reference implementation)

innsegl init -repo /path/to/your/repo -trust-root self-hosted \
  -spire-address 127.0.0.1:18081 -trust-domain innsegl.dev \
  -admin-svid svid.pem -admin-key key.pem -admin-bundle bundle.pem \
  -oidc-issuer http://spire-oidc:8080 -fulcio-url http://127.0.0.1:5555 -rekor-url http://127.0.0.1:3010

make spire-admin-relay-down   # ALWAYS run this
```

**Measured**, against a throwaway repository, on this stack:

```
VERIFIED: this deployment can sign. refs/innsegl/init-verify signed a real commit (a142346180b6875f816f5fdf0a6a50c492f4e096) as an orchestrated identity, and `innsegl verify` accepted it. [...]
```

`make spire-admin-relay-down` was confirmed to remove both the container and
the `innsegl-spire-admin-relay` network (`docker ps -a` / `docker network ls`
show neither afterwards).

### What is exposed, and for how long

The raw SPIRE admin TCP API, bound to `127.0.0.1:18081` on the host, for as
long as `spire-admin-relay` is left running — which is entirely up to the
operator remembering the second command.

### Failure mode if the operator forgets to undo it

**Loopback limits this to "reachable from this machine", not to "reachable by
nobody."** Any other local process — a compromised dev-tool dependency, a
malicious build script, another user's session on a shared workstation — can
open a connection, present its own admin credential (the relay does not check
one; it forwards bytes), and, once it has one, mint or delete registration
entries anywhere in the trust domain. The relay does not expire itself and
carries no timeout; it runs until `spire-admin-relay-down` (or the whole
stack) is torn down. This is a real, standing local attack surface that
depends entirely on operator memory to close — the failure mode the issue
named as the one that matters most.

---

## Option 3 — the fully manual step, undocumented before this runbook

No compose change at all. The operator builds the same relay by hand, the way
the issue's own reference tunnel does, and tears it down by hand.

### What an operator types

```sh
docker run -d --name innsegl-adminrelay --publish 127.0.0.1:18082:8081 \
  alpine/socat:1.8.0.3 tcp-listen:8081,fork,reuseaddr tcp-connect:innsegl-spire-server:8081
docker network connect innsegl-spire-admin innsegl-adminrelay

# mint credentials and run innsegl init exactly as in Option 1, against
# 127.0.0.1:18082

docker rm --force innsegl-adminrelay   # ALWAYS run this
```

**Measured**, against a throwaway repository, on this stack:

```
VERIFIED: this deployment can sign. refs/innsegl/init-verify signed a real commit (00850a925400d75c6190e8a32a24852bf2fc712e) as an orchestrated identity, and `innsegl verify` accepted it. [...]
```

`docker rm --force innsegl-adminrelay` was confirmed to remove the container
completely (`docker ps -a` shows nothing named `innsegl-adminrelay`
afterwards); it used the default bridge network, which nothing else here
owns, so no network cleanup step is needed.

### What is exposed, and for how long

Identical to Option 1 — the raw admin API on `127.0.0.1:18082` — for as long
as the operator leaves `innsegl-adminrelay` running.

### Failure mode if the operator forgets to undo it

Identical to Option 1, and arguably worse in practice: there is no `make
spire-admin-relay-down` to remember, no line in `docker compose ps` grouping
it with the rest of the stack, and no compose profile to make its existence
visible to `docker compose --profile adminrelay ps`. A relay started this way
is a bare container an operator has to remember exists at all, with a name
they chose themselves and may not choose consistently next time.

---

## Recommendation

**Option 2 — run `innsegl init` inside the deployment.** The single strongest
reason: it is the only one of the three whose failure mode, if the operator
forgets a step, is *nothing* — no exposure survives a `run --rm` container
that already exited, because none was ever created. Options 1 and 3 both
trade a real, standing local-admin exposure for less operator typing during
setup, and the issue is explicit that a forgotten open admin port is the
worse failure to optimize against. Option 2's costs (`-gitsign-path` required,
a host bind mount, a possible `safe.directory` step on Linux) are all paid
once, at `init` time, and none of them persist afterwards the way Options 1
and 3's open port does if left running.

Option 1 is shipped anyway (`spire-admin-relay`, off by default) because it is
close to zero-cost to maintain, matches the shape every test harness already
uses, and gives an operator who wants to inspect the admin API directly (or
run something other than `innsegl init` against it) a supported, named way to
do that instead of reaching for `docker run` by hand — which Option 3 remains,
documented above for exactly that reason, and is not otherwise recommended
over Option 2.

**No `commit.gpgsign` behaviour of `innsegl init` needed to change for any of
the three options** — all three reached it exactly as shipped, through the
existing `-spire-address` / `-admin-svid` / `-workload-api` flags.

**Doc 05 §1 is unchanged.** `spire-admin-relay` and `innsegl-init` are not
services doc 05 §1 lists, the same way `demo-agent` and `innsegl-canary`
are not: both are off by a compose profile, both run to completion or exist
only while switched on, and neither is part of what a plain `docker compose
up` brings up. If a future change makes either of them always-on, that
becomes a doc 05 §1 row and a question for the human, not a wiring detail —
see `.claude/CLAUDE.md`'s rule against editing the specs to match an
inference.
