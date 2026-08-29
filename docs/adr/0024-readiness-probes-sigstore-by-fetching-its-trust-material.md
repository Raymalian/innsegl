# ADR-0024: Define Sigstore reachability as serving parseable trust material, and keep every readiness probe read-only

- Status: accepted
- Date: 2026-08-29
- Deciders: Mike

## Context

IP §6.6 states the requirement in one sentence:

> Health endpoints: `ready` is false unless SPIRE, ledger, and Sigstore are all
> reachable; per-dependency status is exposed so operators see *which*
> dependency is failing.

Doc 07's MCP-012 turns it into a test: block each dependency in turn, and the
failing one is named while the others are reported healthy. Doc 05 §2 adds one
field — "the §6.8 skew bound is a config value surfaced in health output".

Three forces shape how that can be built, and none of them is about the report
format.

**"Reachable" is not defined anywhere, and the three dependencies do not admit
one definition.** SPIRE is an authenticated gRPC admin API behind an OPA policy
(ADR-0012). The ledger is a Postgres pool behind a schema. Sigstore is two HTTP
services, and after ADR-0010 it is *whichever* Fulcio/Rekor pair the deployment
configured, since self-hosted is now the shipped default. Each needs its own
answer, and each answer is a trade between cost, blast radius and how much it
actually proves.

**A readiness probe cannot write.** I3 makes the ledger the product and I4 makes
it append-only; a probe polled by every load-balancer replica that appended an
event would fill the chain with noise that can never be removed. Rekor is
append-only by construction and has the same problem. Fulcio issues real
certificates. So the strongest possible probe — do the thing and see if it
works — is unavailable for two of the three, and undesirable for the third.

**The opposite failure is worse and is the one that gets shipped.** A TCP dial,
or an HTTP GET whose body is never examined, succeeds against anything that is
listening: a reverse proxy with a stale upstream, an unrelated service on a
reused port, a 200 error page. That check never fails. During the outage it is
supposed to detect it reports green, and the operator spends the incident
looking somewhere else. A check that never fails is worse than no check,
because it also destroys the credibility of the checks beside it.

There is a fourth force specific to this repository. IP §2's branch floor
requires 100% branch coverage on every error-return path, and doc 01 §2 requires
integration cases to run against real dependencies — "a mocked Fulcio proves
nothing about I5". `deploy/compose/` today carries the SPIRE trio and nothing
else: Fulcio and Rekor are listed in doc 05 §1 but land with RM-030 (#38).

## Decision

**Reachability is defined per dependency as the cheapest read that fails when
the dependency would fail, and no probe writes anything.**

- **SPIRE** — `ListAgents`, via `spire.Client.AttestedNodes`. It is chosen from
  the methods `deploy/compose/spire/authz-policy.rego` *already* grants the MCP
  admin credential, so readiness costs no widening of the admin surface, and it
  exercises the whole path a tool uses: mTLS with the admin SVID, the server-ID
  authorization, and the OPA policy. IP §6.1 makes "could not be reached **or**
  could not answer" one class, and an authorization denial is the second half of
  that sentence — which a TCP dial would miss. It creates nothing.

- **Ledger** — `ledger.Store.Head`: one indexed read of the chain tip. It proves
  the pool holds a usable connection, that the `innsegl` schema is present, and
  that the chain is readable. `pool.Ping` would prove only the socket. It writes
  nothing.

- **Sigstore** — each half must serve its **trust material**, and the bytes must
  parse as that material: Fulcio's root at `/api/v1/rootCert` must decode as a
  PEM **CA** certificate, Rekor's key at `/api/v1/log/publicKey` must decode as
  a PKIX public key. Both are unauthenticated GETs of artifacts the services
  must publish before they can do anything at all, so they fail exactly when
  signing would fail for reasons of availability. Both paths are configuration,
  defaulted to those values.

**Sigstore is reported as one dependency whose class names which half is down.**
IP §6.3 already spells that distinction — Fulcio down is `SIGNING_UNAVAILABLE`,
Rekor down is `TRANSPARENCY_UNAVAILABLE` — so the report needs no nested
structure to answer "which service?". Both halves are probed on every call even
when the first fails, so "one service is gone" is distinguishable from "the
Sigstore deployment is gone". When both fail the class is `SIGNING_UNAVAILABLE`
(IP §4 order) and the detail names both.

**The three probes run concurrently, each under its own deadline.** Sequentially
they would share one budget, and the common shape of a real outage is a
dependency that hangs rather than refusing; it would consume the budget and time
the others out behind it. The report would then go uniformly red and name the
wrong systems, which is the exact failure MCP-012 exists to catch.

**Liveness contacts nothing, and has no false case.** `Live()` reports the
process, the advertised tool surface and the version. The answer to "Postgres is
down" is never "restart the MCP"; a liveness check wired to dependencies turns
one dependency's outage into a restart loop across every replica. The only way
the liveness endpoint reports not-alive is by failing to answer, which is what a
liveness probe measures and what a restart repairs.

**A missing probe is refused at construction.** `NewHealth` returns
`INVARIANT_VIOLATION` if any of the three is nil. A nil probe would have to be
read as healthy — reporting a dependency reachable that was never contacted —
or as unhealthy, which makes a misconfigured deployment indistinguishable from
an outage. Neither is reportable.

**The clock-skew bound is surfaced, never invented.** Zero means "not
configured" and is *absent* from the wire rather than rendered `"0s"`, which an
operator would read as "this deployment tolerates no skew at all". IP §6.8 owns
the bound's value and VER-005 owns its boundary test; a default chosen in a
health file would silently become the project's bound.

**An incomplete tool surface is reported and does not gate readiness.**
`sign_commit` lands in E5, so v0.1 advertises four of five tools.
`missing_tools` appears in both reports — `Server.MissingTools` names this duty
— but refusing traffic for the four tools that exist because a fifth does not
would be a self-inflicted outage.

## Alternatives considered

**A signing round trip: mint a JWT-SVID, get a Fulcio certificate, log a Rekor
entry.** It is the only probe that proves Sigstore will do its job, and it loses
on two independent grounds, either sufficient. It is a *write* — a real
certificate and a real entry in an append-only log, from every replica, forever.
And it would make the health endpoint the dominant load on the CA. Rejected as
a probe; it belongs in E5's end-to-end path, where it happens once and for a
reason.

**A TCP dial, or a GET whose status is checked and body ignored.** Cheapest and
useless: it passes against any listening socket. Two concrete cases in this
deployment would slip through — a reverse proxy answering for a dead Fulcio, and
a port reused by an unrelated service after a compose rename. The probe would
report green for the duration of the outage. Rejected: this is the "check that
never fails" the Context names, and a health endpoint that has ever done this
stops being believed.

**Fulcio's `/api/v2/trustBundle` instead of `/api/v1/rootCert`.** Both were
MEASURED against `https://fulcio.sigstore.dev` on 2026-08-29: `v1/rootCert`
returns HTTP 200, `application/pem-certificate-chain`, 1531 bytes of PEM;
`v2/trustBundle` returns HTTP 200, `application/json`, the same certificate
wrapped in `{"chains":[{"certificates":[...]}]}`. `v1` lost nothing and won on
one point — the check is `pem.Decode` plus `x509.ParseCertificate` with no JSON
shape of Sigstore's to track, so a change to the v2 envelope cannot silently
turn the probe into a check that never fails. The path is configuration, so a
deployment that needs v2 is one config value away, and the *validator* is the
part that would have to change, which is the honest place for that friction.

**Four dependencies — spire, ledger, fulcio, rekor — instead of three.** It
would name the failing half in the `dependency` field rather than in the class.
Rejected because IP §6.6 says three, MCP-012 says three, and the class already
carries the distinction unambiguously; inventing a fourth row would make the
health contract disagree with the spec for no information gain.

**A nested `components` array under the sigstore row.** Same information as the
class, more wire shape for every consumer to parse, and it would have to be
present-and-empty for the other two rows or absent-and-special-cased. Rejected
for cost.

**Making `ready` a single boolean and putting the detail in a log line.** This
is what the issue exists to prevent. An operator reading a log line is an
operator who already knew something was wrong.

**Reporting not-ready when the tool surface is incomplete.** Would make v0.1
permanently unready, since `sign_commit` is E5. Rejected on the facts.

**Waiting for RM-030 to land Fulcio and Rekor in `deploy/compose/`, so MCP-012
could run against real ones.** Rejected because readiness is wanted now, and
because the delay would buy less than it looks like: what MCP-012 has to prove
about *this* code is that a real failure arriving through a real client is
classified and named without contaminating the other two rows. See the
Consequences for exactly what is and is not proven today.

## Consequences

**Readiness cannot prove a dependency is WRITABLE, and this must be said out
loud wherever the endpoint is documented.** A Postgres promoted to a read-only
replica, a full disk, a Fulcio that serves its root and refuses to issue, a
Rekor that serves its key and rejects entries — each answers these probes and is
reported healthy. Proving writability requires a write and a write is not
available here. The failure is still caught, one layer later, by the tools
themselves failing closed (IP §6.4) and by the events that never appear; it is
not caught by readiness, and an operator who believes otherwise is worse off
than one who knows the limit.

**MCP-012's Sigstore half is proved against a real HTTP endpoint, not a real
Fulcio, and this is the one gap in the issue.** `internal/mcp/healthharness_test.go`
blocks the ledger by SIGKILLing a Postgres container of its own (the technique
`internal/ledger` uses for LED-009) and blocks SPIRE by removing the socat proxy
that publishes the admin network's port — closing it for real, so gRPC reports
`connection refused` from the kernel. Sigstore is served by real HTTP listeners
carrying a real X.509 CA certificate and a real ECDSA public key, blocked by
closing the listener. What that proves: the probe, the transport, the parsing
and the classification. What it does not prove: that a real Fulcio and Rekor
serve what this file expects — which is measured against the public instances in
the Alternatives above, and should become an integration case when RM-030 lands
the compose services. **MCP-018** is proposed for it: the same probe against
`deploy/compose/`'s own Fulcio and Rekor, with each container stopped in turn.

**The three dependency names become part of a wire contract.** `spire`,
`ledger`, `sigstore`, and the field names of the readiness document, are read by
operators, by whatever scrapes `/readyz`, and by the dashboard (doc 06). They
are not on VERSIONING.md's protected-surface list and this ADR does not add them
— but changing one breaks a monitoring configuration silently, which is the
property that list exists to describe. Treat a rename as a documented breaking
change.

**`/healthz` and `/readyz` are chosen here, not by a spec.** No document fixes
them. They are constants in the source so a deployment manifest and a test
cannot disagree, and the handler is `GET`-only: this process holds SPIRE admin,
and a health surface that accepted a body would be a second door into it.

**The admin authorization policy is now load-bearing for readiness.** Removing
`ListAgents` from `mcp_admin_methods` in `authz-policy.rego` would make every
replica permanently unready, with `IDENTITY_UNAVAILABLE` naming SPIRE — correct
behaviour, confusing cause. The rego file's comment already lists `ListAgents`
as needed by `register_agent`; readiness is a second dependent.

**Exit cost, if this is ever reversed.** Low. The probe surfaces are interfaces
(`HealthIdentities`, `HealthLedger`, `HealthSigstore`), so E5's Fulcio client
can supersede `SigstoreEndpoints` by satisfying the third one, and a deployment
that wants a different endpoint sets a config value. Reversing the *definition*
of reachability changes one function per dependency and the tests that pin it;
nothing persists, because a health check writes nothing.
